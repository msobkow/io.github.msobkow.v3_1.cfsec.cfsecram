
// Description: Java 25 in-memory RAM DbIO implementation for SecSysRole.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSysRoleTable in-memory RAM DbIO implementation
 *	for SecSysRole.
 */
public class CFSecRamSecSysRoleTable
	implements ICFSecSecSysRoleTable
{
	private ICFSecSchema schema;
	private Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
				CFSecBuffSecSysRole > dictByPKey
		= new HashMap< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$,
				CFSecBuffSecSysRole >();
	private Map< CFSecBuffSecSysRoleByUNameIdxKey,
			CFSecBuffSecSysRole > dictByUNameIdx
		= new HashMap< CFSecBuffSecSysRoleByUNameIdxKey,
			CFSecBuffSecSysRole >();

	public CFSecRamSecSysRoleTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysRole ensureRec(ICFSecSecSysRole rec) {
		return (((CFSecBuffSecSysRoleFactoryService)(schema.getCFSecBuffFactory().getFactorySecSysRole())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSysRole createSecSysRole( ICFSecAuthorization Authorization,
		ICFSecSecSysRole iBuff )
	{
		final String S_ProcName = "createSecSysRole";
		
		CFSecBuffSecSysRole Buff = (CFSecBuffSecSysRole)ensureRec(iBuff);
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ pkey;
		pkey = schema.nextSecSysGrpIdGen();
		Buff.setRequiredSecSysRoleId( pkey );
		CFSecBuffSecSysRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecSysRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUNameIdx.containsKey( keyUNameIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecSysRoleUNameIdx",
				"SecSysRoleUNameIdx",
				keyUNameIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.put( keyUNameIdx, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysRole.CLASS_CODE) {
				CFSecBuffSecSysRole retbuff = ((CFSecBuffSecSysRole)(schema.getCFSecBuffFactory().getFactorySecSysRole().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysRole readDerived( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readDerived";
		ICFSecSecSysRole buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRole lockDerived( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRole.lockDerived";
		ICFSecSecSysRole buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRole[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysRole.readAllDerived";
		ICFSecSecSysRole[] retList = new ICFSecSecSysRole[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysRole > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysRole readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ Name )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readDerivedByUNameIdx";
		CFSecBuffSecSysRoleByUNameIdxKey key = (CFSecBuffSecSysRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRole().newByUNameIdxKey();

		key.setRequiredName( Name );
		ICFSecSecSysRole buff;
		if( dictByUNameIdx.containsKey( key ) ) {
			buff = dictByUNameIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRole readDerivedByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readDerivedByIdIdx() ";
		ICFSecSecSysRole buff;
		if( dictByPKey.containsKey( SecSysRoleId ) ) {
			buff = dictByPKey.get( SecSysRoleId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRole readRec( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readRec";
		ICFSecSecSysRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRole lockRec( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysRole buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysRole.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRole[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readAllRec";
		ICFSecSecSysRole buff;
		ArrayList<ICFSecSecSysRole> filteredList = new ArrayList<ICFSecSecSysRole>();
		ICFSecSecSysRole[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRole.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRole[0] ) );
	}

	@Override
	public ICFSecSecSysRole readRecByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readRecByIdIdx() ";
		ICFSecSecSysRole buff = readDerivedByIdIdx( Authorization,
			SecSysRoleId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRole.CLASS_CODE ) ) {
			return( (ICFSecSecSysRole)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysRole readRecByUNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ Name )
	{
		final String S_ProcName = "CFSecRamSecSysRole.readRecByUNameIdx() ";
		ICFSecSecSysRole buff = readDerivedByUNameIdx( Authorization,
			Name );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRole.CLASS_CODE ) ) {
			return( (ICFSecSecSysRole)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecSysRole updateSecSysRole( ICFSecAuthorization Authorization,
		ICFSecSecSysRole iBuff )
	{
		CFSecBuffSecSysRole Buff = (CFSecBuffSecSysRole)ensureRec(iBuff);
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ pkey = ($iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$)Buff.getPKey();
		CFSecBuffSecSysRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysRole",
				"Existing record not found",
				"Existing record not found",
				"SecSysRole",
				"SecSysRole",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysRole",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysRoleByUNameIdxKey existingKeyUNameIdx = (CFSecBuffSecSysRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRole().newByUNameIdxKey();
		existingKeyUNameIdx.setRequiredName( existing.getRequiredName() );

		CFSecBuffSecSysRoleByUNameIdxKey newKeyUNameIdx = (CFSecBuffSecSysRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRole().newByUNameIdxKey();
		newKeyUNameIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyUNameIdx.equals( newKeyUNameIdx ) ) {
			if( dictByUNameIdx.containsKey( newKeyUNameIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecSysRole",
					"SecSysRoleUNameIdx",
					"SecSysRoleUNameIdx",
					newKeyUNameIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecSysRole > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUNameIdx.remove( existingKeyUNameIdx );
		dictByUNameIdx.put( newKeyUNameIdx, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysRole( ICFSecAuthorization Authorization,
		ICFSecSecSysRole iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysRoleTable.deleteSecSysRole() ";
		CFSecBuffSecSysRole Buff = (CFSecBuffSecSysRole)ensureRec(iBuff);
		int classCode;
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ pkey = ($iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$)(Buff.getPKey());
		CFSecBuffSecSysRole existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysRole",
				pkey );
		}
					schema.getTableSecSysRoleMemb().deleteSecSysRoleMembBySysRoleIdx( Authorization,
						existing.getRequiredSecSysRoleId() );
					schema.getTableSecSysRoleEnables().deleteSecSysRoleEnablesBySysRoleIdx( Authorization,
						existing.getRequiredSecSysRoleId() );
		CFSecBuffSecSysRoleByUNameIdxKey keyUNameIdx = (CFSecBuffSecSysRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRole().newByUNameIdxKey();
		keyUNameIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$, CFSecBuffSecSysRole > subdict;

		dictByPKey.remove( pkey );

		dictByUNameIdx.remove( keyUNameIdx );

	}
	@Override
	public void deleteSecSysRoleByIdIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysRole cur;
		LinkedList<CFSecBuffSecSysRole> matchSet = new LinkedList<CFSecBuffSecSysRole>();
		Iterator<CFSecBuffSecSysRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRole)(schema.getTableSecSysRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId() ));
			deleteSecSysRole( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysRoleByUNameIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argName )
	{
		CFSecBuffSecSysRoleByUNameIdxKey key = (CFSecBuffSecSysRoleByUNameIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRole().newByUNameIdxKey();
		key.setRequiredName( argName );
		deleteSecSysRoleByUNameIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleByUNameIdxKey argKey )
	{
		CFSecBuffSecSysRole cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysRole> matchSet = new LinkedList<CFSecBuffSecSysRole>();
		Iterator<CFSecBuffSecSysRole> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRole> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRole)(schema.getTableSecSysRole().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId() ));
			deleteSecSysRole( Authorization, cur );
		}
	}
}
