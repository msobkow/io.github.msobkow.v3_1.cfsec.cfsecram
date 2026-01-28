
// Description: Java 25 in-memory RAM DbIO implementation for ISOLang.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOLangTable in-memory RAM DbIO implementation
 *	for ISOLang.
 */
public class CFSecRamISOLangTable
	implements ICFSecISOLangTable
{
	private ICFSecSchema schema;
	private Map< Short,
				CFSecBuffISOLang > dictByPKey
		= new HashMap< Short,
				CFSecBuffISOLang >();
	private Map< CFSecBuffISOLangByCode3IdxKey,
			CFSecBuffISOLang > dictByCode3Idx
		= new HashMap< CFSecBuffISOLangByCode3IdxKey,
			CFSecBuffISOLang >();
	private Map< CFSecBuffISOLangByCode2IdxKey,
				Map< Short,
					CFSecBuffISOLang >> dictByCode2Idx
		= new HashMap< CFSecBuffISOLangByCode2IdxKey,
				Map< Short,
					CFSecBuffISOLang >>();

	public CFSecRamISOLangTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffISOLang ensureRec(ICFSecISOLang rec) {
		if (rec == null) {
			return( null );
		}
		else {
			int classCode = rec.getClassCode();
			if (classCode == ICFSecISOLang.CLASS_CODE) {
				return( ((CFSecBuffISOLangDefaultFactory)(schema.getFactoryISOLang())).ensureRec(rec) );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), "ensureRec", "rec", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOLang createISOLang( ICFSecAuthorization Authorization,
		ICFSecISOLang iBuff )
	{
		final String S_ProcName = "createISOLang";
		
		CFSecBuffISOLang Buff = ensureRec(iBuff);
		Short pkey;
		pkey = schema.nextISOLangIdGen();
		Buff.setRequiredISOLangId( pkey );
		CFSecBuffISOLangByCode3IdxKey keyCode3Idx = (CFSecBuffISOLangByCode3IdxKey)schema.getFactoryISOLang().newByCode3IdxKey();
		keyCode3Idx.setRequiredISO6392Code( Buff.getRequiredISO6392Code() );

		CFSecBuffISOLangByCode2IdxKey keyCode2Idx = (CFSecBuffISOLangByCode2IdxKey)schema.getFactoryISOLang().newByCode2IdxKey();
		keyCode2Idx.setOptionalISO6391Code( Buff.getOptionalISO6391Code() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByCode3Idx.containsKey( keyCode3Idx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOLang6392Idx",
				"ISOLang6392Idx",
				keyCode3Idx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByCode3Idx.put( keyCode3Idx, Buff );

		Map< Short, CFSecBuffISOLang > subdictCode2Idx;
		if( dictByCode2Idx.containsKey( keyCode2Idx ) ) {
			subdictCode2Idx = dictByCode2Idx.get( keyCode2Idx );
		}
		else {
			subdictCode2Idx = new HashMap< Short, CFSecBuffISOLang >();
			dictByCode2Idx.put( keyCode2Idx, subdictCode2Idx );
		}
		subdictCode2Idx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecISOLang.CLASS_CODE) {
				CFSecBuffISOLang retbuff = ((CFSecBuffISOLang)(schema.getFactoryISOLang().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	public ICFSecISOLang readDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOLang.readDerived";
		ICFSecISOLang buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOLang lockDerived( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOLang.readDerived";
		ICFSecISOLang buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOLang[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOLang.readAllDerived";
		ICFSecISOLang[] retList = new ICFSecISOLang[ dictByPKey.values().size() ];
		Iterator< CFSecBuffISOLang > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecISOLang readDerivedByCode3Idx( ICFSecAuthorization Authorization,
		String ISO6392Code )
	{
		final String S_ProcName = "CFSecRamISOLang.readDerivedByCode3Idx";
		CFSecBuffISOLangByCode3IdxKey key = (CFSecBuffISOLangByCode3IdxKey)schema.getFactoryISOLang().newByCode3IdxKey();
		key.setRequiredISO6392Code( ISO6392Code );

		ICFSecISOLang buff;
		if( dictByCode3Idx.containsKey( key ) ) {
			buff = dictByCode3Idx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOLang[] readDerivedByCode2Idx( ICFSecAuthorization Authorization,
		String ISO6391Code )
	{
		final String S_ProcName = "CFSecRamISOLang.readDerivedByCode2Idx";
		CFSecBuffISOLangByCode2IdxKey key = (CFSecBuffISOLangByCode2IdxKey)schema.getFactoryISOLang().newByCode2IdxKey();
		key.setOptionalISO6391Code( ISO6391Code );

		ICFSecISOLang[] recArray;
		if( dictByCode2Idx.containsKey( key ) ) {
			Map< Short, CFSecBuffISOLang > subdictCode2Idx
				= dictByCode2Idx.get( key );
			recArray = new ICFSecISOLang[ subdictCode2Idx.size() ];
			Iterator< CFSecBuffISOLang > iter = subdictCode2Idx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< Short, CFSecBuffISOLang > subdictCode2Idx
				= new HashMap< Short, CFSecBuffISOLang >();
			dictByCode2Idx.put( key, subdictCode2Idx );
			recArray = new ICFSecISOLang[0];
		}
		return( recArray );
	}

	public ICFSecISOLang readDerivedByIdIdx( ICFSecAuthorization Authorization,
		short ISOLangId )
	{
		final String S_ProcName = "CFSecRamISOLang.readDerivedByIdIdx() ";
		ICFSecISOLang buff;
		if( dictByPKey.containsKey( ISOLangId ) ) {
			buff = dictByPKey.get( ISOLangId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOLang readRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "CFSecRamISOLang.readRec";
		ICFSecISOLang buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOLang.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOLang lockRec( ICFSecAuthorization Authorization,
		Short PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecISOLang buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecISOLang.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecISOLang[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOLang.readAllRec";
		ICFSecISOLang buff;
		ArrayList<ICFSecISOLang> filteredList = new ArrayList<ICFSecISOLang>();
		ICFSecISOLang[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOLang.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOLang[0] ) );
	}

	public ICFSecISOLang readRecByIdIdx( ICFSecAuthorization Authorization,
		short ISOLangId )
	{
		final String S_ProcName = "CFSecRamISOLang.readRecByIdIdx() ";
		ICFSecISOLang buff = readDerivedByIdIdx( Authorization,
			ISOLangId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOLang.CLASS_CODE ) ) {
			return( (ICFSecISOLang)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOLang readRecByCode3Idx( ICFSecAuthorization Authorization,
		String ISO6392Code )
	{
		final String S_ProcName = "CFSecRamISOLang.readRecByCode3Idx() ";
		ICFSecISOLang buff = readDerivedByCode3Idx( Authorization,
			ISO6392Code );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOLang.CLASS_CODE ) ) {
			return( (ICFSecISOLang)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecISOLang[] readRecByCode2Idx( ICFSecAuthorization Authorization,
		String ISO6391Code )
	{
		final String S_ProcName = "CFSecRamISOLang.readRecByCode2Idx() ";
		ICFSecISOLang buff;
		ArrayList<ICFSecISOLang> filteredList = new ArrayList<ICFSecISOLang>();
		ICFSecISOLang[] buffList = readDerivedByCode2Idx( Authorization,
			ISO6391Code );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecISOLang.CLASS_CODE ) ) {
				filteredList.add( (ICFSecISOLang)buff );
			}
		}
		return( filteredList.toArray( new ICFSecISOLang[0] ) );
	}

	public ICFSecISOLang updateISOLang( ICFSecAuthorization Authorization,
		ICFSecISOLang iBuff )
	{
		CFSecBuffISOLang Buff = ensureRec(iBuff);
		Short pkey = Buff.getPKey();
		CFSecBuffISOLang existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOLang",
				"Existing record not found",
				"Existing record not found",
				"ISOLang",
				"ISOLang",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOLang",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffISOLangByCode3IdxKey existingKeyCode3Idx = (CFSecBuffISOLangByCode3IdxKey)schema.getFactoryISOLang().newByCode3IdxKey();
		existingKeyCode3Idx.setRequiredISO6392Code( existing.getRequiredISO6392Code() );

		CFSecBuffISOLangByCode3IdxKey newKeyCode3Idx = (CFSecBuffISOLangByCode3IdxKey)schema.getFactoryISOLang().newByCode3IdxKey();
		newKeyCode3Idx.setRequiredISO6392Code( Buff.getRequiredISO6392Code() );

		CFSecBuffISOLangByCode2IdxKey existingKeyCode2Idx = (CFSecBuffISOLangByCode2IdxKey)schema.getFactoryISOLang().newByCode2IdxKey();
		existingKeyCode2Idx.setOptionalISO6391Code( existing.getOptionalISO6391Code() );

		CFSecBuffISOLangByCode2IdxKey newKeyCode2Idx = (CFSecBuffISOLangByCode2IdxKey)schema.getFactoryISOLang().newByCode2IdxKey();
		newKeyCode2Idx.setOptionalISO6391Code( Buff.getOptionalISO6391Code() );

		// Check unique indexes

		if( ! existingKeyCode3Idx.equals( newKeyCode3Idx ) ) {
			if( dictByCode3Idx.containsKey( newKeyCode3Idx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOLang",
					"ISOLang6392Idx",
					"ISOLang6392Idx",
					newKeyCode3Idx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< Short, CFSecBuffISOLang > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByCode3Idx.remove( existingKeyCode3Idx );
		dictByCode3Idx.put( newKeyCode3Idx, Buff );

		subdict = dictByCode2Idx.get( existingKeyCode2Idx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByCode2Idx.containsKey( newKeyCode2Idx ) ) {
			subdict = dictByCode2Idx.get( newKeyCode2Idx );
		}
		else {
			subdict = new HashMap< Short, CFSecBuffISOLang >();
			dictByCode2Idx.put( newKeyCode2Idx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	public void deleteISOLang( ICFSecAuthorization Authorization,
		ICFSecISOLang iBuff )
	{
		final String S_ProcName = "CFSecRamISOLangTable.deleteISOLang() ";
		CFSecBuffISOLang Buff = ensureRec(iBuff);
		int classCode;
		Short pkey = (Short)(Buff.getPKey());
		CFSecBuffISOLang existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOLang",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckISOLangCountries[] = schema.getTableISOCtryLang().readDerivedByLangIdx( Authorization,
						existing.getRequiredISOLangId() );
		if( arrCheckISOLangCountries.length > 0 ) {
			schema.getTableISOCtryLang().deleteISOCtryLangByLangIdx( Authorization,
						existing.getRequiredISOLangId() );
		}
		CFSecBuffISOLangByCode3IdxKey keyCode3Idx = (CFSecBuffISOLangByCode3IdxKey)schema.getFactoryISOLang().newByCode3IdxKey();
		keyCode3Idx.setRequiredISO6392Code( existing.getRequiredISO6392Code() );

		CFSecBuffISOLangByCode2IdxKey keyCode2Idx = (CFSecBuffISOLangByCode2IdxKey)schema.getFactoryISOLang().newByCode2IdxKey();
		keyCode2Idx.setOptionalISO6391Code( existing.getOptionalISO6391Code() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< Short, CFSecBuffISOLang > subdict;

		dictByPKey.remove( pkey );

		dictByCode3Idx.remove( keyCode3Idx );

		subdict = dictByCode2Idx.get( keyCode2Idx );
		subdict.remove( pkey );

	}
	public void deleteISOLangByIdIdx( ICFSecAuthorization Authorization,
		Short argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffISOLang cur;
		LinkedList<CFSecBuffISOLang> matchSet = new LinkedList<CFSecBuffISOLang>();
		Iterator<CFSecBuffISOLang> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOLang> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOLang)(schema.getTableISOLang().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOLangId() ));
			deleteISOLang( Authorization, cur );
		}
	}

	public void deleteISOLangByCode3Idx( ICFSecAuthorization Authorization,
		String argISO6392Code )
	{
		CFSecBuffISOLangByCode3IdxKey key = (CFSecBuffISOLangByCode3IdxKey)schema.getFactoryISOLang().newByCode3IdxKey();
		key.setRequiredISO6392Code( argISO6392Code );
		deleteISOLangByCode3Idx( Authorization, key );
	}

	public void deleteISOLangByCode3Idx( ICFSecAuthorization Authorization,
		ICFSecISOLangByCode3IdxKey argKey )
	{
		CFSecBuffISOLang cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOLang> matchSet = new LinkedList<CFSecBuffISOLang>();
		Iterator<CFSecBuffISOLang> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOLang> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOLang)(schema.getTableISOLang().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOLangId() ));
			deleteISOLang( Authorization, cur );
		}
	}

	public void deleteISOLangByCode2Idx( ICFSecAuthorization Authorization,
		String argISO6391Code )
	{
		CFSecBuffISOLangByCode2IdxKey key = (CFSecBuffISOLangByCode2IdxKey)schema.getFactoryISOLang().newByCode2IdxKey();
		key.setOptionalISO6391Code( argISO6391Code );
		deleteISOLangByCode2Idx( Authorization, key );
	}

	public void deleteISOLangByCode2Idx( ICFSecAuthorization Authorization,
		ICFSecISOLangByCode2IdxKey argKey )
	{
		CFSecBuffISOLang cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalISO6391Code() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffISOLang> matchSet = new LinkedList<CFSecBuffISOLang>();
		Iterator<CFSecBuffISOLang> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffISOLang> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffISOLang)(schema.getTableISOLang().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOLangId() ));
			deleteISOLang( Authorization, cur );
		}
	}
}
